rule TTP_XOR_QUAD_CurrentVersionRun_a43a {
  strings:
    $key_a43a = { f7 55 [2] d3 5b [2] f8 77 [2] d6 55 [2] c2 4e [2] cd 54 [2] d3 49 [2] d1 48 [2] ca 4e [2] d6 49 [2] ca 66 }

  condition:
    any of them
}