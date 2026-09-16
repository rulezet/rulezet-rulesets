rule infostealer_win_stealc_str_oct24 {
  meta:
    id             = "7448fafe-206c-4f9c-b5a3-cbabec12a45b"
    version        = "1.0"
    description    = "Finds Stealc standalone samples (or dumps) based on the strings"
    author         = "Sekoia.io"
    creation_date  = "2024-10-20"
    classification = "TLP:CLEAR"

  strings:
    $str01 = "-nop -c \"iex(New-Object Net.WebClient).DownloadString(" ascii      $str02 = "Azure\\.IdentityService" ascii      $str03 = "steam_tokens.txt" ascii
    $str04 = "\"encrypted_key\":\"" ascii      $str05 = "prefs.js" ascii      $str06 = "browser: FileZilla" ascii
    $str07 = "profile: null" ascii
    $str08 = "url:" ascii
    $str09 = "login:" ascii
    $str10 = "password:" ascii      $str11 = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" ascii      $str12 = "ChromeFuckNewCookies" ascii      $str13 = "/c timeout /t 10 & del /f /q \"" ascii  
  condition:
    uint16(0) == 0x5A4D and 9 of them
}