rule _20160921_2eacd3ef1ce6866325342ce8cba80e38_20160921_5d6863feab41_3586 {
  meta:
    description = "datamaliciousorder - from files 20160921_2eacd3ef1ce6866325342ce8cba80e38.js, 20160921_5d6863feab411af8217516a1b111aa40.js, 20160921_95ced062e0552048d29cf59daab852db.js, 20160921_b71168af39c5eec1d403d381eea7ffe1.js, 20160921_e6569e3fc498e9fab243cf8dcef2ac51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "128e4fae256d5c8ef6708fbd7f51b17e3da126d63b88361b0e92c9808a0c393f"
    hash2       = "0dbd74ce266dbd495fb6fc7810ec67099f628d975c524a9190f91ccc4bf433bb"
    hash3       = "62e6b62d08a320533bdb97151951141555c4f9ccf26ad306c0e21644b883ab60"
    hash4       = "c8811edeb74999e8dd226f7fa9d7963ccfc998904ecb9474d036376253dc6fde"
    hash5       = "d08c501a52afbdcde7669d2b9c40865025e38aa75b2aebf8c71433565dbc7010"

  strings:
    $s1 = "f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"NB" ascii
    $s2 = "n \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s3 = "0(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Go\";" ascii
    $s4 = "urn \"Qa\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(f" ascii
    $s5 = "n \"UOt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"MJq\";})(),(f" ascii
    $s6 = "f000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"HJ" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}