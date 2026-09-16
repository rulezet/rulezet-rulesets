rule TTP_XOR_QUAD_CurrentVersionRun_c162 {
  strings:
    $key_c162 = { 92 0d [2] b6 03 [2] 9d 2f [2] b3 0d [2] a7 16 [2] a8 0c [2] b6 11 [2] b4 10 [2] af 16 [2] b3 11 [2] af 3e }

  condition:
    any of them
}