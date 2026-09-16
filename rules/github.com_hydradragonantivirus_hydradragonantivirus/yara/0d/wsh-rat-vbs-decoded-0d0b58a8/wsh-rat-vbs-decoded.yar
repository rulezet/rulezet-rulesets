rule wsh_rat_vbs_decoded {
  meta:
    author      = "jeFF0Falltrades"
    ref         = "https://cofense.com/houdini-worm-transformed-new-phishing-attack"
    description = "Alerts on the decoded WSH RAT VBScript"

  strings:
    $str_0  = "wshsdk" wide ascii nocase
    $str_1  = "wshlogs" wide ascii nocase
    $str_2  = "WSHRAT" wide ascii nocase
    $str_3  = "WSH Sdk for password recovery" wide ascii nocase
    $str_4  = "wshlogs\\recovered_password_email.log" wide ascii nocase
    $str_5  = "post (\"is-ready\",\"\")" wide ascii nocase
    $str_6  = "split (response,spliter)" wide ascii nocase
    $str_7  = "updatestatus(\"SDK+Already+Installed\")" wide ascii nocase
    $str_8  = "case \"get-pass-offline\"" wide ascii nocase
    $str_9  = "case \"up-n-exec\"" wide ascii nocase
    $str_10 = "Unable to automatically recover password" wide ascii nocase
    $str_11 = "reverseproxy" wide ascii nocase
    $str_12 = "keyloggerstarter" wide ascii nocase

  condition:
    3 of ($str*)
}