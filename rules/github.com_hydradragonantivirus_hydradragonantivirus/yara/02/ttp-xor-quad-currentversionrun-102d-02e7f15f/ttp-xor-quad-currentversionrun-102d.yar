rule TTP_XOR_QUAD_CurrentVersionRun_102d {
  strings:
    $key_102d = { 43 42 [2] 67 4c [2] 4c 60 [2] 62 42 [2] 76 59 [2] 79 43 [2] 67 5e [2] 65 5f [2] 7e 59 [2] 62 5e [2] 7e 71 }

  condition:
    any of them
}