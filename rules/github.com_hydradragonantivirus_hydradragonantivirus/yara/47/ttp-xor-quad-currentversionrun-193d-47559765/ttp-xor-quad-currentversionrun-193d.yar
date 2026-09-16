rule TTP_XOR_QUAD_CurrentVersionRun_193d {
  strings:
    $key_193d = { 4a 52 [2] 6e 5c [2] 45 70 [2] 6b 52 [2] 7f 49 [2] 70 53 [2] 6e 4e [2] 6c 4f [2] 77 49 [2] 6b 4e [2] 77 61 }

  condition:
    any of them
}