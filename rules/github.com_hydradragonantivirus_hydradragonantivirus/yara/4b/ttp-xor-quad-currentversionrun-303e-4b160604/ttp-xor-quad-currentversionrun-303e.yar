rule TTP_XOR_QUAD_CurrentVersionRun_303e {
  strings:
    $key_303e = { 63 51 [2] 47 5f [2] 6c 73 [2] 42 51 [2] 56 4a [2] 59 50 [2] 47 4d [2] 45 4c [2] 5e 4a [2] 42 4d [2] 5e 62 }

  condition:
    any of them
}