rule Virus_Hijack_Gen_Trojan_ShellObject_f8Y_aSZtDuk_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5447001a78616401ce4a95789980454a4cca48362603fa9c50be020c90be98b7"

  strings:
    $s1  = "{0}.Execute - starting task execution" fullword wide
    $s2  = "DownloadPackageTask::Execute: Package name member is null or empty" fullword wide
    $s3  = "DownloadPackageAttachmentTask::Execute: {0} Failed to create the BITS job: {1}" fullword wide
    $s4  = "This is benign and likely due to some process (often ehshell.exe) holding a file open in the directory." fullword wide
    $s5  = "Download Package Complete - {0}" fullword wide
    $s6  = "DownloadPackageTask: starting download - '{0}'" fullword wide
    $s7  = "UploadPackageTask::Execute: Package name member is null or empty" fullword wide
    $s8  = "DownloadPackageAttachmentTask::Execute: Attachment member is null" fullword wide
    $s9  = "DownloadPackageAttachmentTask::Execute: Package name member is null or empty" fullword wide
    $s10 = "DownloadPackageAttachmentTask::Execute: {0} Invalid package directory path" fullword wide
    $s11 = "DownloadPackageAttachmentTask::Execute: Attachment filename is null or empty" fullword wide
    $s12 = "UploadPackageTask: nothing to export - '{0}'. [{1}]" fullword wide
    $s13 = "BaseUpdateTask::Execute: Input session is null" fullword wide
    $s14 = "DownloadPackageTask: subscription has been locked for package: {0}" fullword wide
    $s15 = "DownloadPackageTask: failed to get service locator url -> no retry" fullword wide
    $s16 = "Execute: FDICreate failed with error code/type: {0}/{1}." fullword wide
    $s17 = "GetSecurityTokenTask: Security token download complete" fullword wide
    $s18 = "Guide/Update/CrlDownload.cpp: Failed to load cpfilters.dll 0x{0:X}" fullword wide
    $s19 = "DownloadPackageTask::FindWebServiceLocator: Subscription member is null" fullword wide
    $s20 = "UpdateSession: execute [{0}] failed aborting." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}