rule sig_20160315_932d8266c3a1976d7ce840df8419315a {
  meta:
    description = "datamaliciousorder - file 20160315_932d8266c3a1976d7ce840df8419315a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e5373aa3833052ddfe8a7395460c965e5897c72b5786031875e5aaa0ec6a2e4"

  strings:
    $s1  = "    jlHIaNJf = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&     " ascii
    $s2  = "+\"Xuph\"+\"ol\"+\"stered\"+\"ML\"+\"up\"+\"ho\"+\"lstered2\" + (\"salaries\",\"transvaal\",\"sydney\",\".\")+(\"penis\",\"modul" ascii
    $s3  = "    CuSNe.open((\"menus\",\"prints\",\"G\")+\"ET\", (\"manchester\",\"goody\",\"shares\",\"http:\")+(\"sandwich\",\"womankind\"," ascii
    $s4  = "bitch = XWziato[3 * 5 - 3 * 3].split(\"upholstered\").join(\"\");" fullword ascii
    $s5  = "CuSNe.onreadystatechange = function () {" fullword ascii
    $s6  = "String.prototype.ladies = function () { return this.substr(0, 1); };" fullword ascii
    $s7  = "        FzEkqoPYnu = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {   " ascii
    $s8  = "zzle.error( match[0] );     \";" fullword ascii
    $s9  = "var IIMWWs = this[bitch];" fullword ascii
    $s10 = "SyqalLY = \" filter: {\";" fullword ascii
    $s11 = "        FzEkqoPYnu = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {   " ascii
    $s12 = "IPwnrmmRt = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s13 = "ent\")+(\"alleged\",\"governance\",\"million\",\"seasick\",\"Strings\"), \"\"+\"%\"+(\"comes\",\"omissions\",\"TE\")+(\"vicariou" ascii
    $s14 = "    jlHIaNJf = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&     " ascii
    $s15 = "        srDNEJ = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s16 = "        qPjesbjBAq = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s17 = "    EIuGmgWH[XWziato[introspectiveI+1]](CzrJpofi, 1, \"jJnRWEk\" === \"cUvYwXINlqP\"); EUtWOPD = \"  \\\"TAG\\\": function( node" ascii
    $s18 = "} catch (jBonkWu) { };" fullword ascii

  condition:
    uint16(0) == 0x4c4d and
    8 of them
}