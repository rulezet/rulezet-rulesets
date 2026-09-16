rule sig_20160525_fe36ac4c2ae88dace304d1ceb57bab1d {
  meta:
    description = "datamaliciousorder - file 20160525_fe36ac4c2ae88dace304d1ceb57bab1d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51ea443863bd354d408b9405a91808f8cdb7e5796a9b978edab2bc88c53c3c38"

  strings:
    $s1 = "};tsilslianbmuhtog nruter{)(ssorcah noitcnuf( + ssorcag + sdnetg + deerdg[tpircSW = gsmb rav    \\n{\\n)ima ,tsilslianbmuhtoa(su" ascii
    $s2 = ";};imb nruter{)imb(rerednerb noitcnuf\\n;\"733x\\\\4\" = imc rav\\n;\"tt86x\\\\\" = eixodd rav\\n;\":07x\\\\\" = gsmd rav\\n;\"f" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}