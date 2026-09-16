rule TTP_XOR_QUAD_CurrentVersionRun_301c {
  strings:
    $key_301c = { 63 73 [2] 47 7d [2] 6c 51 [2] 42 73 [2] 56 68 [2] 59 72 [2] 47 6f [2] 45 6e [2] 5e 68 [2] 42 6f [2] 5e 40 }

  condition:
    any of them
}