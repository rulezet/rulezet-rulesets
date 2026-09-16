rule sig_20160621_9108c7a9043603e053789cbbda56d769 {
  meta:
    description = "datamaliciousorder - file 20160621_9108c7a9043603e053789cbbda56d769.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c70064a0a20e3732d47952f0fe9ce3ede00c4968036041bbab253150c918bc54"

  strings:
    $x1  = "var l52 = new Array();l52[41] = ',\"';l52[40] = 'u\"';l52[876] = 'EC%';l52[29] = '[\"damo';l52[235] = 'lse i';l52[854] = 'YPT.t'" ascii
    $s2  = "&id';l52[845] = 'UserPr';l52[835] = 'MSPEC%';l52[341] = ' other';l52[520] = 'low';l52[755] = 'SZ /';l52[909] = 'COMSP';l52[30] =" ascii
    $s3  = ";l52[767] = 'C% /c';l52[666] = 'men';l52[530] = 'ecrypt';l52[64] = 'dE';l52[215] = 'se i';l52[453] = 'g sear';l52[295] = 'st';l5" ascii
    $s4  = "eL';l52[572] = 'your f';l52[643] = ' soft';l52[17] = 'ng.fro';l52[743] = 'AD';l52[223] = 'e\",2';l52[371] = ' fp';l52[376] = 're" ascii
    $s5  = "var l52 = new Array();l52[41] = ',\"';l52[40] = 'u\"';l52[876] = 'EC%';l52[29] = '[\"damo';l52[235] = 'lse i';l52[854] = 'YPT.t'" ascii
    $s6  = "ware,';l52[797] = 'xe';l52[406] = 'ne(\"\")';l52[556] = '\"+ad);';l52[305] = '.Cr';l52[960] = 'lse)';l52[885] = 'cq,0,';l52[279]" ascii
    $s7  = ";l52[178] = 'n(); ';l52[664] = 'u make';l52[74] = 's+\"';l52[16] = '=Stri';l52[574] = 's.';l52[639] = 'dat';l52[212] = 'h(er){';" ascii
    $s8  = "2[632] = 'to ';l52[670] = 'it';l52[289] = '?a';l52[722] = '\"+';l52[893] = ',true';l52[304] = 'fo';l52[511] = 'fp.Wr';l52[712] =" ascii
    $s9  = "Write';l52[955] = '\"+id+';l52[42] = 'quan-';l52[799] = 's+c';l52[300] = ' xo.s';l52[35] = 'vok';l52[900] = '.Wr';l52[89] = 'ts." ascii
    $s10 = "t';l52[370] = '\");';l52[543] = 'i++) {';l52[677] = 'can';l52[726] = '+\" ';l52[435] = '/ne';l52[537] = 'r (';l52[382] = ' have " ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and all of them
}