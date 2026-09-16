rule browser_pass
{
    meta:
        author = "swood"
        description = "This module is intended for forensicators and pen-testers to find passwords in memory that can help their case/engagement." 
                reference = "https://github.com/swoodsec/YARA-RULES/blob/master/browserpass.yar"

    strings:
        $1 = "Passwd="
        $2 = "passwd="
        $3 = "Password="
        $4 = "password="
        $5 = "Pwd="
        $6 = "pwd="
        $7 = "Pass="
        $8 = "pass="
        $9 = "session_password="
        $10 = "Session_Password="

    condition:
        any of them
}