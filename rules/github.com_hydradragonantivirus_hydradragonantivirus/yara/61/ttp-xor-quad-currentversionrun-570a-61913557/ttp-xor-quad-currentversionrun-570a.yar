rule TTP_XOR_QUAD_CurrentVersionRun_570a {
  strings:
    $key_570a = { 04 65 [2] 20 6b [2] 0b 47 [2] 25 65 [2] 31 7e [2] 3e 64 [2] 20 79 [2] 22 78 [2] 39 7e [2] 25 79 [2] 39 56 }

  condition:
    any of them
}