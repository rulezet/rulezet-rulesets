rule TTP_XOR_QUAD_CurrentVersionRun_164a {
  strings:
    $key_164a = { 45 25 [2] 61 2b [2] 4a 07 [2] 64 25 [2] 70 3e [2] 7f 24 [2] 61 39 [2] 63 38 [2] 78 3e [2] 64 39 [2] 78 16 }

  condition:
    any of them
}