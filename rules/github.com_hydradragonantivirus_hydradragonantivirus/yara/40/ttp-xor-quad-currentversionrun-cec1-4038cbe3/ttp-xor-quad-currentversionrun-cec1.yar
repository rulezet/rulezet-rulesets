rule TTP_XOR_QUAD_CurrentVersionRun_cec1 {
  strings:
    $key_cec1 = { 9d ae [2] b9 a0 [2] 92 8c [2] bc ae [2] a8 b5 [2] a7 af [2] b9 b2 [2] bb b3 [2] a0 b5 [2] bc b2 [2] a0 9d }

  condition:
    any of them
}