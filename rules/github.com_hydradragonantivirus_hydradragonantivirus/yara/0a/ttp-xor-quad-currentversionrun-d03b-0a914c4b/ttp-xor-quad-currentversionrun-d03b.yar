rule TTP_XOR_QUAD_CurrentVersionRun_d03b {
  strings:
    $key_d03b = { 83 54 [2] a7 5a [2] 8c 76 [2] a2 54 [2] b6 4f [2] b9 55 [2] a7 48 [2] a5 49 [2] be 4f [2] a2 48 [2] be 67 }

  condition:
    any of them
}