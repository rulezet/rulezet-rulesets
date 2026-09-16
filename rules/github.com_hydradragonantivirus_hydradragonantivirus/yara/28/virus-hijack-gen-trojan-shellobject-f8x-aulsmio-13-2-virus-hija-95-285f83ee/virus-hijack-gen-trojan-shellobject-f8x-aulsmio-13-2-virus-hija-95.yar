rule _Virus_Hijack_Gen_Trojan_ShellObject_f8X_auLSMIo_13_2_Virus_Hija_95 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8X@auLSMIo_13_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@auLSMIo_3_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk_16.vir, Virus.Hijack_Gen.Trojan.ShellObject.fCY@aijlKSl_13_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_12_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqsS8zj_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46f1de8097af7239c37586320ffde5ca0fd686a57108d3a6e92836f8af6e1bb1"
    hash2       = "b9b6d8d4e5e6cd4b77e5a6c7210788216aa3bb117891716f5015552052351ce2"
    hash3       = "b48311d90cd631f1f9f853683b479e0566d82f9f8391f92ea4220366aa48e7b7"
    hash4       = "9a6b5f7a0086cacfc765ffd2bd404a4dc3c398aeee8ae86ff5391c27bb2c5187"
    hash5       = "d9431bfa0b15c0664e6da4d8c617ce5d2b9dc9af0016c8be47246bcb74418c95"
    hash6       = "525840a20b13e36d24d9dd94a491b8079a93decb970473acaad045e14cb0641a"

  strings:
    $s1  = "postamble, resp_handle, resp_body, resp_header, resp_params  from resource_request_operations  where rid=?  order by req_order A" ascii
    $s2  = " select method, req_header, req_body, req_flags, req_URL, req_handle, req_order, rid, req_status, req_params, req_preamble, req_" ascii
    $s3  = " select method, req_header, req_body, req_flags, req_URL, req_handle, req_order, rid, req_status, req_params, req_preamble, req_" ascii
    $s4  = "postamble, resp_handle, resp_body, resp_header, resp_params  from resource_request_operations  where rid=?  and req_order =?" fullword ascii
    $s5  = " create table resource_request_operations(rid integer not null, method text(8) default NULL, req_header text(512) default NULL, " ascii
    $s6  = "Mozilla/3.0 (compatible; Adobe Synchronizer 11.0.07)" fullword ascii
    $s7  = "e text(512) default NULL, resp_header text(512) default NULL, req_flags integer not null, req_order integer not null, req_status" ascii
    $s8  = "t NULL, req_params text(256) default NULL, req_preamble text(512) default NULL, req_postamble text(512) default NULL, resp_handl" ascii
    $s9  = " update resource_request_operations  set method=? , req_header=? , req_body=? , req_flags=? , req_URL=? , req_handle=? , req_par" ascii
    $s10 = " integer not null, resp_params text(256) default NULL )" fullword ascii
    $s11 = "ams=? , req_preamble=? , req_postamble=? , resp_handle=?    where rid=? and req_order=?" fullword ascii
    $s12 = "@delete from recentfiles where localfileaccesstime= (select min( localfileaccesstime ) from recentfiles )  AND (select count( lo" ascii
    $s13 = "ecentfiles where servermd5=? and assetid=?  order by localfileaccesstime DESC" fullword ascii
    $s14 = "select fid, localpath, filename, filesys, localfilemodifiedtime, localfileaccesstime, localfilesize, localdipath, assetid from r" ascii
    $s15 = "ecentfiles where localpath=? " fullword ascii
    $s16 = "select fid, filename, filesys, localfilemodifiedtime, localfileaccesstime, localfilesize, localdipath, assetid, servermd5 from r" ascii
    $s17 = "select fid, localpath, filename, filesys, localfilemodifiedtime, localfileaccesstime, localfilesize, localdipath, assetid from r" ascii
    $s18 = "ocaldipath text(512) unique, assetid text(512), servermd5 text(512) , lock integer default 0 )" fullword ascii
    $s19 = "caldipath ) from recentfiles)>?" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}