rule Virus_Hijack_Generic_Dacic_2527_020ED395_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Generic.Dacic.2527.020ED395_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8529634e52160f151208181a3357ee39e0321a6eda2afa984e13d3e4d84ed741"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Wind#ws)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s2 = "wareAgent=\"Adobe Photoshop CC 2018 (Wind#ws)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s3 = "\"xmp.iid:d9d77401-7124-ed42-8b71-4014b651f934\" stRef:documentID=\"adobe:docid:photoshopSee396c7e-5800-2842-91eb-924792347dc3\"" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}