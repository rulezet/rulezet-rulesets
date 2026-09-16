rule TTP_XOR_QUAD_CurrentVersionRun_053e {
  strings:
    $key_053e = { 56 51 [2] 72 5f [2] 59 73 [2] 77 51 [2] 63 4a [2] 6c 50 [2] 72 4d [2] 70 4c [2] 6b 4a [2] 77 4d [2] 6b 62 }

  condition:
    any of them
}