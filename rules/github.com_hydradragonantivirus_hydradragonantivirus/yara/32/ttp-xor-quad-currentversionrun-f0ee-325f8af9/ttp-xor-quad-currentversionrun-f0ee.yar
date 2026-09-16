rule TTP_XOR_QUAD_CurrentVersionRun_f0ee {
  strings:
    $key_f0ee = { a3 81 [2] 87 8f [2] ac a3 [2] 82 81 [2] 96 9a [2] 99 80 [2] 87 9d [2] 85 9c [2] 9e 9a [2] 82 9d [2] 9e b2 }

  condition:
    any of them
}