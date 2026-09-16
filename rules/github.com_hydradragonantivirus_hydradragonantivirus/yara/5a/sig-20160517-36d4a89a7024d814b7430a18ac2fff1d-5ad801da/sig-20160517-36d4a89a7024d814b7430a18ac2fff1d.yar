rule sig_20160517_36d4a89a7024d814b7430a18ac2fff1d {
  meta:
    description = "datamaliciousorder - file 20160517_36d4a89a7024d814b7430a18ac2fff1d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9542bc6e3d4dac9ee70fa243a218677ec6da4a5cd0d7b25bbde4230ac0323edf"

  strings:
    $s1 = "var cfreyj='vu24itadjsfmrolxli jqesina3phnesrnpkwifmurksob3xxwcjprevbiay4pm2kxudlpba=exjqr\\'g1fg4tb3grrcvnxksnffewtilkewqfi1nwq" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}