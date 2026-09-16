rule TTP_XOR_QUAD_CurrentVersionRun_e0eb {
  strings:
    $key_e0eb = { b3 84 [2] 97 8a [2] bc a6 [2] 92 84 [2] 86 9f [2] 89 85 [2] 97 98 [2] 95 99 [2] 8e 9f [2] 92 98 [2] 8e b7 }

  condition:
    any of them
}