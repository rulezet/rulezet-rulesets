rule TTP_XOR_QUAD_CurrentVersionRun_0a20 {
  strings:
    $key_0a20 = { 59 4f [2] 7d 41 [2] 56 6d [2] 78 4f [2] 6c 54 [2] 63 4e [2] 7d 53 [2] 7f 52 [2] 64 54 [2] 78 53 [2] 64 7c }

  condition:
    any of them
}