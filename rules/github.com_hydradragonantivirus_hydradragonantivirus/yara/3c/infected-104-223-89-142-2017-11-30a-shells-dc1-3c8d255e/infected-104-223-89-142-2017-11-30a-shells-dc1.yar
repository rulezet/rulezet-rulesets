rule infected_104_223_89_142_2017_11_30a_shells_dc1 {
  meta:
    description = "shells - file dc1.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-10-28"
    hash1       = "21bfa2844fc3856efa205ae3a85799bce7bed07e48546f1063c87ef4f247af16"

  strings:
    $s1  = "file_put_contents($Folder.\"wp-newsletter-v1.php\", base64_decode(\"PD9waHANCkBkYXRlX2RlZmF1bHRfdGltZXpvbmVfc2V0KCdFdXJvcGUvTG9u" ascii
    $s2  = "xLDR9KXs1fTp8KD8hKD86LipbYS1mMC05XTopezYsfSkoPz5bYS1mMC05XXsxLDR9KD8+OlthLWYwLTldezEsNH0pezAsNH0pPycgLiAnOjooPz4oPzpbYS1mMC05XXs" ascii  
    $s3  = "7M30gT0sgaWQ9KC4qKS8nLCAnc2VuZG1haWwnID0+ICcvWzAtOV17M30gMi4wLjAgKC4qKSBNZXNzYWdlLycsICdwb3N0Zml4JyA9PiAnL1swLTldezN9IDIuMC4wIE9" ascii  
    $s4  = "gJHRoaXMtPnNldEVycm9yKCJUaGUgcmVxdWVzdGVkIGF1dGhlbnRpY2F0aW9uIG1ldGhvZCBcIiRhdXRodHlwZVwiIGlzIG5vdCBzdXBwb3J0ZWQgYnkgdGhlIHNlcnZ" ascii  
    $s5  = "fc2VsZWN0b3IpICYmICghZW1wdHkoJHRoaXMtPkRLSU1fcHJpdmF0ZV9zdHJpbmcpIHx8ICghZW1wdHkoJHRoaXMtPkRLSU1fcHJpdmF0ZSkgJiYgZmlsZV9leGlzdHM" ascii  
    $s6  = "gb3IgJEZpbGVTY2FuID09ICIuLiIgb3IgaXNfZGlyKCRGaWxlU2Nhbikgb3IgIWlzX2ZpbGUoJEZpbGVTY2FuKSBvciAkRmlsZVNjYW4gPT0gYmFzZW5hbWUoX19GSUx" ascii  
    $s7  = "kZWJ1ZygiQ29ubmVjdGlvbjogb3BlbmluZyB0byAkaG9zdDokcG9ydCwgc29ja3M9eyR0aGlzLT5Tb2Nrc0hvc3R9OnskdGhpcy0+U29ja3NQb3J0fSwgdGltZW91dD0" ascii  
    $s8  = "xOyBhPScgLiAkREtJTXNpZ25hdHVyZVR5cGUgLiAnOyBxPScgLiAkREtJTXF1ZXJ5IC4gJzsgbD0nIC4gJERLSU1sZW4gLiAnOyBzPScgLiAkdGhpcy0+REtJTV9zZWx" ascii  
    $s9  = "3Rl18XFxcW1x4MDAtXHhGRl0pKSoiKScgLiAnKD8+XC4oPz5bISMtXCcqK1wvLTk9P14tfi1dK3wiKD8+KD8+W1x4MDEtXHgwOFx4MEJceDBDXHgwRS0hIy1cW1xdLVx" ascii  
    $s10 = "pcy0+bWFpbEhlYWRlciAuPSAkdGhpcy0+aGVhZGVyTGluZSgnU3ViamVjdCcsICR0aGlzLT5lbmNvZGVIZWFkZXIoJHRoaXMtPnNlY3VyZUhlYWRlcih0cmltKCR0aGl" ascii  
    $s11 = "haWwnXSAuICImc3ViamVjdD0iIC4gJF9HRVRbJ3N1YmplY3QnXSAuICImZnJvbT0iIC4gJF9HRVRbJ2Zyb20nXSAuICImcmVhbF91cmw9IiAuICRfR0VUWydyZWFsX3V" ascii  
    $s12 = "pKD8+OicgLiAnW2EtZjAtOV17MSw0fSl7N318KD8hKD86LipbYS1mMC05XVs6XF1dKXs4LH0pKD8+W2EtZjAtOV17MSw0fSg/PjpbYS1mMC05XXsxLDR9KXswLDZ9KT8" ascii  
    $s13 = "gIHNlbGY6OmVkZWJ1ZygnQXV0aCBtZXRob2QgcmVxdWVzdGVkOiAnIC4gKCRhdXRodHlwZSA/ICRhdXRodHlwZSA6ICdVTktOT1dOJyksIHNlbGY6OkRFQlVHX0xPV0x" ascii  
    $s14 = "kcmVzdWx0IC49ICR0aGlzLT5oZWFkZXJMaW5lKCdTdWJqZWN0JywgJHRoaXMtPmVuY29kZUhlYWRlcigkdGhpcy0+c2VjdXJlSGVhZGVyKCR0aGlzLT5TdWJqZWN0KSk" ascii  
    $s15 = "gR2V0UGFnZUNvbnRlbnQodXJsZGVjb2RlKCRfR0VUWydyZWFsX3VybCddKSAuICI/Y2hlY2tfaW5ib3hfcGhwX2FjdGlvbj10cnVlJmVtYWlsPSIgLiAkX0dFVFsnZW1" ascii  
    $s16 = "wRFx4MEEpP1tcdCBdKyk/KShcKCg/Pig/MiknIC4gJyg/PltceDAxLVx4MDhceDBCXHgwQ1x4MEUtXCcqLVxbXF0tXHg3Rl18XFxcW1x4MDAtXHg3Rl18KD8zKSkpKig" ascii  
    $s17 = "/ISg/Pig/MSkiPyg/PlxcXFsgLX5dfFteIl0pIj8oPzEpKXs2NSx9QCknIC4gJygoPz4oPz4oPz4oKD8+KD8+KD8+XHgwRFx4MEEpP1tcdCBdKSt8KD8+W1x0IF0qXHg" ascii  
    $s18 = "oPz5cXFxbIC1+XXxbXiJdKSI/KXs2NSx9QCkoPz4nIC4gJ1shIy1cJyorXC8tOT0/Xi1+LV0rfCIoPz4oPz5bXHgwMS1ceDA4XHgwQlx4MENceDBFLSEjLVxbXF0tXHg" ascii  
    $s19 = "nIC4gJzo6KD8+W2EtZjAtOV17MSw0fSg/PjpbYS1mMC05XXsxLDR9KXswLDZ9KT8pKXwoPz4oPz5JUHY2Oig/PlthLWYwLTldezEsNH0oPz46JyAuICdbYS1mMC05XXs" ascii  
    $s20 = "7MSw0fSkoPz46KD82KSl7N30nIC4gJ3woPyEoPzouKlthLWYwLTldWzpcXV0pezgsfSkoKD82KSg/PjooPzYpKXswLDZ9KT86Oig/Nyk/KSl8KD8+KD8+SVB2NjooPz4" ascii  

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 600KB and
      (8 of them)
    ) or (all of them)
}