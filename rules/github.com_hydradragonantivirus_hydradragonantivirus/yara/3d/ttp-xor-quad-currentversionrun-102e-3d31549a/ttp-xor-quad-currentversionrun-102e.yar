rule TTP_XOR_QUAD_CurrentVersionRun_102e {
  strings:
    $key_102e = { 43 41 [2] 67 4f [2] 4c 63 [2] 62 41 [2] 76 5a [2] 79 40 [2] 67 5d [2] 65 5c [2] 7e 5a [2] 62 5d [2] 7e 72 }

  condition:
    any of them
}