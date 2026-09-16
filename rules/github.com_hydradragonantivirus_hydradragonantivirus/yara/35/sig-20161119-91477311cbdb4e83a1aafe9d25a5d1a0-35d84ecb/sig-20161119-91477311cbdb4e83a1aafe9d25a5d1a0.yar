rule sig_20161119_91477311cbdb4e83a1aafe9d25a5d1a0 {
  meta:
    description = "datamaliciousorder - file 20161119_91477311cbdb4e83a1aafe9d25a5d1a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f87cbaddea38e4be246294e210192c44ac8b34eb930cb8423dee76f4cc583307"

  strings:
    $s1 = "var ilyvnodb8 = new Function(smoronjoltex0 + ystiji4 + rorwezuzmix1 + anfys9 + etrytyxs0 + pditivaqv1 + axruxotacmo7 + crekbif7 " ascii
    $s2 = "var qbitdebda0 = new Function(qgifqucixuv2 + ivtuc7 + tonmosuwbi2 + dakukruxg1 + ygzasimjo7 + qrukdilzo0 + oxgepa5 + pyvyxipti5 " ascii
    $s3 = "var ilyvnodb8 = new Function(smoronjoltex0 + ystiji4 + rorwezuzmix1 + anfys9 + etrytyxs0 + pditivaqv1 + axruxotacmo7 + crekbif7 " ascii
    $s4 = "var uxajx9 = this;" fullword ascii
    $s5 = "var qbitdebda0 = new Function(qgifqucixuv2 + ivtuc7 + tonmosuwbi2 + dakukruxg1 + ygzasimjo7 + qrukdilzo0 + oxgepa5 + pyvyxipti5 " ascii

  condition:
    uint16(0) == 0x7241 and
    all of them
}