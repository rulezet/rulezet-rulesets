rule TTP_XOR_QUAD_CurrentVersionRun_623f {
  strings:
    $key_623f = { 31 50 [2] 15 5e [2] 3e 72 [2] 10 50 [2] 04 4b [2] 0b 51 [2] 15 4c [2] 17 4d [2] 0c 4b [2] 10 4c [2] 0c 63 }

  condition:
    any of them
}