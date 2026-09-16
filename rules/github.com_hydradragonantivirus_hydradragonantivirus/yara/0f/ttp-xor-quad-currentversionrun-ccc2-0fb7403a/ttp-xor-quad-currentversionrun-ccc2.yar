rule TTP_XOR_QUAD_CurrentVersionRun_ccc2 {
  strings:
    $key_ccc2 = { 9f ad [2] bb a3 [2] 90 8f [2] be ad [2] aa b6 [2] a5 ac [2] bb b1 [2] b9 b0 [2] a2 b6 [2] be b1 [2] a2 9e }

  condition:
    any of them
}