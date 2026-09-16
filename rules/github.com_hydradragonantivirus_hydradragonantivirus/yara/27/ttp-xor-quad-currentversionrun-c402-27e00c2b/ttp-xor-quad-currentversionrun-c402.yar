rule TTP_XOR_QUAD_CurrentVersionRun_c402 {
  strings:
    $key_c402 = { 97 6d [2] b3 63 [2] 98 4f [2] b6 6d [2] a2 76 [2] ad 6c [2] b3 71 [2] b1 70 [2] aa 76 [2] b6 71 [2] aa 5e }

  condition:
    any of them
}