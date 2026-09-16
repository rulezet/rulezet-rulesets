rule sig_20161024_43139d0f71da66694738995fcc4598c3 {
  meta:
    description = "datamaliciousorder - file 20161024_43139d0f71da66694738995fcc4598c3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd2c3bf8db8389e7e258c8370c57d1a3a45b5297712fa0674eb59d9f6920863f"

  strings:
    $s1 = "} while (ko++ < go);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}