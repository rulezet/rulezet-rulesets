rule TTP_XOR_QUAD_CurrentVersionRun_271f {
  strings:
    $key_271f = { 74 70 [2] 50 7e [2] 7b 52 [2] 55 70 [2] 41 6b [2] 4e 71 [2] 50 6c [2] 52 6d [2] 49 6b [2] 55 6c [2] 49 43 }

  condition:
    any of them
}