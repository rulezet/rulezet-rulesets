rule TTP_XOR_QUAD_CurrentVersionRun_e0ee {
  strings:
    $key_e0ee = { b3 81 [2] 97 8f [2] bc a3 [2] 92 81 [2] 86 9a [2] 89 80 [2] 97 9d [2] 95 9c [2] 8e 9a [2] 92 9d [2] 8e b2 }

  condition:
    any of them
}