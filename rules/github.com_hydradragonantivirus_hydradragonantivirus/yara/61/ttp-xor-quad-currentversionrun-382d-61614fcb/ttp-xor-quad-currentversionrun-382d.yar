rule TTP_XOR_QUAD_CurrentVersionRun_382d {
  strings:
    $key_382d = { 6b 42 [2] 4f 4c [2] 64 60 [2] 4a 42 [2] 5e 59 [2] 51 43 [2] 4f 5e [2] 4d 5f [2] 56 59 [2] 4a 5e [2] 56 71 }

  condition:
    any of them
}