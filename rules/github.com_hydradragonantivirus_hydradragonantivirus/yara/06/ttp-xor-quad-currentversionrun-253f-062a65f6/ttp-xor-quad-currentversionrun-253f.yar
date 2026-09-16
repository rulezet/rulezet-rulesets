rule TTP_XOR_QUAD_CurrentVersionRun_253f {
  strings:
    $key_253f = { 76 50 [2] 52 5e [2] 79 72 [2] 57 50 [2] 43 4b [2] 4c 51 [2] 52 4c [2] 50 4d [2] 4b 4b [2] 57 4c [2] 4b 63 }

  condition:
    any of them
}