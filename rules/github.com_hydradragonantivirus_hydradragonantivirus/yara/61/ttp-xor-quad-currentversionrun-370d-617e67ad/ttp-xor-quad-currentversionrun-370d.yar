rule TTP_XOR_QUAD_CurrentVersionRun_370d {
  strings:
    $key_370d = { 64 62 [2] 40 6c [2] 6b 40 [2] 45 62 [2] 51 79 [2] 5e 63 [2] 40 7e [2] 42 7f [2] 59 79 [2] 45 7e [2] 59 51 }

  condition:
    any of them
}