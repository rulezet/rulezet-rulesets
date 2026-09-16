rule TTP_XOR_QUAD_CurrentVersionRun_c0ee {
  strings:
    $key_c0ee = { 93 81 [2] b7 8f [2] 9c a3 [2] b2 81 [2] a6 9a [2] a9 80 [2] b7 9d [2] b5 9c [2] ae 9a [2] b2 9d [2] ae b2 }

  condition:
    any of them
}