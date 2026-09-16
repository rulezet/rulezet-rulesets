rule sig_20160210_765dede108263e39e4eecf07c4c25cb0 {
  meta:
    description = "datamaliciousorder - file 20160210_765dede108263e39e4eecf07c4c25cb0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c29496b4b727b0ddc727b5098809752670498a973ca52ef81062357176dcfc9b"

  strings:
    $s1 = "    while (aCwlUJzXR['' + ('tfxL', 'hBcpDA', 'HM4Q', 'PBt3', 'rQhi'.g()) + 'ea' + ('l0q', 'gXA2fc', 'FPQZ', 'dC3nWS'.g()) + 'ys'" ascii
    $s2 = "print(a79UmyZfb, (((2-1)^(0+0))&((1508/29)-(140-89)))-(((29+1)-(30-14))-((420&498)/(0|32))), (((0+0)^(3-3))|((1+0)*(1&1)))-(((8-" ascii
    $s3 = "    while (aCwlUJzXR['' + ('tfxL', 'hBcpDA', 'HM4Q', 'PBt3', 'rQhi'.g()) + 'ea' + ('l0q', 'gXA2fc', 'FPQZ', 'dC3nWS'.g()) + 'ys'" ascii
    $s4 = "    function String.prototype.g () {return this.split('').reverse().pop();}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    all of them
}