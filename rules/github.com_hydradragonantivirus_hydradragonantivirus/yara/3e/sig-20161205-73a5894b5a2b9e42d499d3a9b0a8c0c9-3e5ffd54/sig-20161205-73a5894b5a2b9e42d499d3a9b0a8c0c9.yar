rule sig_20161205_73a5894b5a2b9e42d499d3a9b0a8c0c9 {
  meta:
    description = "datamaliciousorder - file 20161205_73a5894b5a2b9e42d499d3a9b0a8c0c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a714f27771c119bafbb68769572d9eb11533a72fd357b150270d365187e4be6"

  strings:
    $s1 = "var myny0 = ['notsy', 'hwocf', 'ratz', 'bivva', 'crermu', 'ygi', 'qroguq', 'ikel', 'natefm', new Function([\"va\", 'mude', 'oloj" ascii
    $s2 = "var xalfuctupco0 = ['ucuqj', 'axik', 'awzecd', new Function(['ivemu', 'opke', 'ikysx', 'evbo', 'usa', 'ibjin', 'wguxuzx', 'cfijf" ascii
    $s3 = "var xalfuctupco0 = ['ucuqj', 'axik', 'awzecd', new Function(['ivemu', 'opke', 'ikysx', 'evbo', 'usa', 'ibjin', 'wguxuzx', 'cfijf" ascii
    $s4 = "var egakgolzo9 = ['fpymh', 'ehra', 'dity', [this][0], 'azbexa', 'axka', 'pgyv', 'efcigk', 'ufvawb', 'avzow', 'dajfels', 'kymi', " ascii
    $s5 = "var myny0 = ['notsy', 'hwocf', 'ratz', 'bivva', 'crermu', 'ygi', 'qroguq', 'ikel', 'natefm', new Function([\"va\", 'mude', 'oloj" ascii
    $s6 = "var egakgolzo9 = ['fpymh', 'ehra', 'dity', [this][0], 'azbexa', 'axka', 'pgyv', 'efcigk', 'ufvawb', 'avzow', 'dajfels', 'kymi', " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}