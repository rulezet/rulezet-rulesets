rule TTP_XOR_QUAD_CurrentVersionRun_151f {
  strings:
    $key_151f = { 46 70 [2] 62 7e [2] 49 52 [2] 67 70 [2] 73 6b [2] 7c 71 [2] 62 6c [2] 60 6d [2] 7b 6b [2] 67 6c [2] 7b 43 }

  condition:
    any of them
}