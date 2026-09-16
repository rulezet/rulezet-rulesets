rule sig_20170221_8851a57e3f9d450f274400cd3b50fec0 {
  meta:
    description = "datamaliciousorder - file 20170221_8851a57e3f9d450f274400cd3b50fec0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d527f78bbd61f1e47c2149a32d6d16cd2c4a9fc552952987a86f89e23e5b4de5"

  strings:
    $s1  = "function getzyqu() {" fullword ascii
    $s2  = "iznuc[ewjyqca]([new String(\"se\"), new String(\"uf\"), new String(\"rg\"), new String(\"y\"), new String(\"es\"), harsu() + dga" ascii
    $s3  = "return [new String(\"yb\"), new String(\"qbi\"), new String(\"y\"), \"cmd.\", new String(\"aj\"), new String(\"e\"), new String(" ascii
    $s4  = "return [new String(\"yb\"), new String(\"qbi\"), new String(\"y\"), \"cmd.\", new String(\"aj\"), new String(\"e\"), new String(" ascii
    $s5  = "ring(\"oshi\"), \"r\" + \"un\", new String(\"ksez\"), new String(\"ygmi\")][7];" fullword ascii
    $s6  = "omwakidt() + ymdyl() + lhyxnukt() + ewoqfucj() + rane() + asicqobw() + aregelc() + kziwa() + utzuwco() + ufzima() + hxijdovpo() " ascii
    $s7  = "var ytmolutnytq = [new String(\"rda\"), new String(\"wpa\"), typeof XMLHttpRequest, new String(\"ura\"), new String(\"ywwe\"), n" ascii
    $s8  = "var ytmolutnytq = [new String(\"rda\"), new String(\"wpa\"), typeof XMLHttpRequest, new String(\"ura\"), new String(\"ywwe\"), n" ascii
    $s9  = "return [new String(\"quvf\"), new String(\"ash\"), new String(\"o\"), new String(\"b\"), new String(\"obp\"), new String(\"o\")," ascii
    $s10 = "\"e\"), new String(\"w\"), new String(\"ehf\"), \"http\"][9];" fullword ascii
    $s11 = "return [new String(\"eli\"), new String(\"e\"), new String(\"dq\"), new String(\"exu\"), new String(\"anba\"), new String(\"pla" ascii
    $s12 = "w String(\"z\"), new String(\"i\")][3];" fullword ascii
    $s13 = "return [new String(\"my\"), new String(\"tmo\"), new String(\"uc\"), new String(\"hec\"), \"';$o\", new String(\"dc\")][4];" fullword ascii
    $s14 = "w String(\"inmi\"), new String(\"tar\"), new String(\"jcu\")][4];" fullword ascii
    $s15 = "w String(\"u\")][1];" fullword ascii
    $s16 = "function pommub() {" fullword ascii
    $s17 = "return [new String(\"fcu\"), \"'^yp\", new String(\"p\"), new String(\"kho\"), new String(\"xdy\"), new String(\"ukle\"), new St" ascii
    $s18 = "var esojeqp = false;" fullword ascii
    $s19 = "function ifik() {" fullword ascii
    $s20 = "function batu() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}