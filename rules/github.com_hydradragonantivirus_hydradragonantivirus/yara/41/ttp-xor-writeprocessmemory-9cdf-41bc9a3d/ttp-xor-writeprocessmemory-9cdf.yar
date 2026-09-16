rule TTP_XOR_WriteProcessMemory_9cdf {
  strings:
    $key_9cdf = { cb ad [2] f9 8f [2] ff ba [2] d1 ba [2] ee a6 }

  condition:
    any of them
}