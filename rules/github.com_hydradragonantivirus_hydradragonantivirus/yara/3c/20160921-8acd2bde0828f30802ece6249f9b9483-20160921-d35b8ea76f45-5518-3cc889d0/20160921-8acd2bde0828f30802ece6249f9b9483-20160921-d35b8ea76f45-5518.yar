rule _20160921_8acd2bde0828f30802ece6249f9b9483_20160921_d35b8ea76f45_5518 {
  meta:
    description = "datamaliciousorder - from files 20160921_8acd2bde0828f30802ece6249f9b9483.js, 20160921_d35b8ea76f45dbc35f302f0ac5357655.js, 20160921_e0f7b2a32a0967097baa59c67369ba3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9cf59fc7ffd1ec7428d01db709ab365cf4dfe41d386ebb308b8bad860ff941b1"
    hash2       = "9dcc5774827243903cab74a4e9a77a6ec68f90a8c6ce60869e9bc7d13bcac921"
    hash3       = "d527617da74d553b6d56b37f7b101c14280b85e5e40e1f565fe396f8b97b29a2"

  strings:
    $s1 = "nction fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){ret" ascii
    $s2 = "(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})" ascii
    $s3 = "tion fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retur" ascii
    $s4 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){ret" ascii
    $s5 = "n fuck(){return \"MBg\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"M" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}