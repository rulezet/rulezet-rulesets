rule _20160921_b71168af39c5eec1d403d381eea7ffe1_20160921_cdeac57ac549_1925 {
  meta:
    description = "datamaliciousorder - from files 20160921_b71168af39c5eec1d403d381eea7ffe1.js, 20160921_cdeac57ac549120611856c7af0c490f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8811edeb74999e8dd226f7fa9d7963ccfc998904ecb9474d036376253dc6fde"
    hash2       = "53694193718c2cb2f90fada2d6a11f07ab2c3f8451a0f41ae580b87a142e212e"

  strings:
    $s1  = "Sj\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functi" ascii
    $s2  = "){return \"DYs\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"XTn\";}" ascii
    $s3  = "eturn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"KDh\";})(" ascii
    $s4  = "h\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(functio" ascii
    $s5  = "n\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Yi\";})(),(function " ascii
    $s6  = "return \"Tb\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(" ascii
    $s7  = "tion f000(){return \"DNa\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"RPt\";})(),(function f000(){retur" ascii
    $s8  = "tion f000(){return \"Nx\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s9  = "(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"RVb\";" ascii
    $s10 = "\"Oh\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Go\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}