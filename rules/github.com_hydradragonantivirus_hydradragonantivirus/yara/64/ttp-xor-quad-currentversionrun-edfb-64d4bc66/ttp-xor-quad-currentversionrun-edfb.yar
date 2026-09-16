rule TTP_XOR_QUAD_CurrentVersionRun_edfb {
  strings:
    $key_edfb = { be 94 [2] 9a 9a [2] b1 b6 [2] 9f 94 [2] 8b 8f [2] 84 95 [2] 9a 88 [2] 98 89 [2] 83 8f [2] 9f 88 [2] 83 a7 }

  condition:
    any of them
}