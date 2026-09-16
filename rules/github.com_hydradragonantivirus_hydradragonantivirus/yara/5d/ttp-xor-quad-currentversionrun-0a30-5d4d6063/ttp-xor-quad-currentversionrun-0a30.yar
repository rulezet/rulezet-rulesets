rule TTP_XOR_QUAD_CurrentVersionRun_0a30 {
  strings:
    $key_0a30 = { 59 5f [2] 7d 51 [2] 56 7d [2] 78 5f [2] 6c 44 [2] 63 5e [2] 7d 43 [2] 7f 42 [2] 64 44 [2] 78 43 [2] 64 6c }

  condition:
    any of them
}