rule sig_20161205_9cd8cf74fbb2b066af89581d83c87045 {
  meta:
    description = "datamaliciousorder - file 20161205_9cd8cf74fbb2b066af89581d83c87045.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22f99e52a9a00654999d9e865397c125b7a917e23b301f29615e7c2c7b5895ee"

  strings:
    $s1 = "var uxjifawu3 = ['wkucven', 'hazke', 'jpenogn', 'yzyh', 'cvana', new Function(['itcor', 'pura', 'ymhut', 'qado', \"va\", 'bbeto'" ascii
    $s2 = "var waktilm = ['bijoq', 'akjotg', 'acgo', 'tsiswek', 'vvidaxg', 'padv', 'gdibsa', 'ugolr', 'ojninby', new Function(['orby', 'ssu" ascii
    $s3 = "var waktilm = ['bijoq', 'akjotg', 'acgo', 'tsiswek', 'vvidaxg', 'padv', 'gdibsa', 'ugolr', 'ojninby', new Function(['orby', 'ssu" ascii
    $s4 = "var kudmynfo1 = ['lmovry', 'umgaty', 'lfyhnufh', 'dkohly', 'igo', 'iztu', 'jinqik', [this][0], 'ytiw', 'sexo', 'tuvar', 'sigju'," ascii
    $s5 = "var uxjifawu3 = ['wkucven', 'hazke', 'jpenogn', 'yzyh', 'cvana', new Function(['itcor', 'pura', 'ymhut', 'qado', \"va\", 'bbeto'" ascii
    $s6 = "var kudmynfo1 = ['lmovry', 'umgaty', 'lfyhnufh', 'dkohly', 'igo', 'iztu', 'jinqik', [this][0], 'ytiw', 'sexo', 'tuvar', 'sigju'," ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}