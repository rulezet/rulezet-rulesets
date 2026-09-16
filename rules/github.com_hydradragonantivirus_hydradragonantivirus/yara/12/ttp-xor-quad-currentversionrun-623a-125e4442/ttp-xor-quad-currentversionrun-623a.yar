rule TTP_XOR_QUAD_CurrentVersionRun_623a {
  strings:
    $key_623a = { 31 55 [2] 15 5b [2] 3e 77 [2] 10 55 [2] 04 4e [2] 0b 54 [2] 15 49 [2] 17 48 [2] 0c 4e [2] 10 49 [2] 0c 66 }

  condition:
    any of them
}