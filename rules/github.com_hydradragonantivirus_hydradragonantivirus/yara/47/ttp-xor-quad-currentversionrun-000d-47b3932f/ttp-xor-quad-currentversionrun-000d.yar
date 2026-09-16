rule TTP_XOR_QUAD_CurrentVersionRun_000d {
  strings:
    $key_000d = { 53 62 [2] 77 6c [2] 5c 40 [2] 72 62 [2] 66 79 [2] 69 63 [2] 77 7e [2] 75 7f [2] 6e 79 [2] 72 7e [2] 6e 51 }

  condition:
    any of them
}