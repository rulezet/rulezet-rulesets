rule TTP_XOR_QUAD_CurrentVersionRun_373f {
  strings:
    $key_373f = { 64 50 [2] 40 5e [2] 6b 72 [2] 45 50 [2] 51 4b [2] 5e 51 [2] 40 4c [2] 42 4d [2] 59 4b [2] 45 4c [2] 59 63 }

  condition:
    any of them
}