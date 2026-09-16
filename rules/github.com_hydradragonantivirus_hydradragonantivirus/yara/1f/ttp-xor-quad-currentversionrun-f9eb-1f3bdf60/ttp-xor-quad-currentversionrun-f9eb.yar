rule TTP_XOR_QUAD_CurrentVersionRun_f9eb {
  strings:
    $key_f9eb = { aa 84 [2] 8e 8a [2] a5 a6 [2] 8b 84 [2] 9f 9f [2] 90 85 [2] 8e 98 [2] 8c 99 [2] 97 9f [2] 8b 98 [2] 97 b7 }

  condition:
    any of them
}