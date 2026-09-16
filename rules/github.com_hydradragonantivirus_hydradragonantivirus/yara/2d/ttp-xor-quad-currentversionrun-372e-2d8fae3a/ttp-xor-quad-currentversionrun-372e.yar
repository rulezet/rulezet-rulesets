rule TTP_XOR_QUAD_CurrentVersionRun_372e {
  strings:
    $key_372e = { 64 41 [2] 40 4f [2] 6b 63 [2] 45 41 [2] 51 5a [2] 5e 40 [2] 40 5d [2] 42 5c [2] 59 5a [2] 45 5d [2] 59 72 }

  condition:
    any of them
}